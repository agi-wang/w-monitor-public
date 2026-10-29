#!/usr/bin/env python3
"""Reconcile a narrowly scoped shared-collector PR using only GITHUB_TOKEN."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPO = "agi-wang/w-monitor-public"
SHARED = "agi-wang/w-monitor-collectors"
PREFIX = "codex/collectors-update-"
MARKER = "w-monitor-collectors-sync:"
BOT = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
FILES = ("Cargo.toml", "Cargo.lock", "server/app.py", "server/openapi.json", "README.md", "PROTOCOL.md")
ALLOWED_DEPS = {"libc", "parking_lot", "serde_json", "sha2", "sysinfo"}
DEPLOY_JOBS = {
    "deploy-receiver (us, public-production)",
    "deploy-receiver (sg, public-singapore)",
    "deploy-receiver (uk, public-united-kingdom)",
    "deploy-receiver (sg-advin, public-singapore-advin)",
    "deploy-receiver (us-mia, public-miami)",
    "deploy-receiver (sg-dap, public-singapore-dapanel)",
    "deploy-receiver (fiber100, public-fiber100)",
}
ROOT = Path(__file__).resolve().parents[1]


class SyncError(RuntimeError):
    pass


class Pending(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def require(condition, message):
    if not condition:
        raise SyncError(message)


def version(value):
    require(isinstance(value, str) and re.fullmatch(r"(?:v)?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value), "Stable semantic version required")
    return tuple(map(int, value.removeprefix("v").split(".")))


def metadata(message):
    match = re.search(r"<!-- " + MARKER + r"(\{[^\n]+\}) -->", message or "")
    require(match is not None, "Unknown branch/PR in reserved automation namespace")
    value = json.loads(match[1])
    require(set(value) == {"base", "shared_tag", "shared_version", "shared_sha", "product_version"}, "Unexpected reconciliation metadata")
    require(all(isinstance(value[key], str) for key in value), "Invalid reconciliation metadata")
    require(all(re.fullmatch(r"[a-f0-9]{40}", value[key]) for key in ("base", "shared_sha")), "Exact commits required")
    require(version(value["shared_tag"]) == version(value["shared_version"]), "Shared tag/version mismatch")
    version(value["product_version"])
    return value


def branch_name(value):
    return PREFIX + value["shared_version"] + "-" + value["shared_sha"][:12]


class GitHub:
    def __init__(self, token, dry_run=False):
        self.token, self.dry_run = token, dry_run
        self.opener = build_opener(NoRedirect())

    def call(self, repo, path, method="GET", data=None, missing=False):
        require(repo in (REPO, SHARED), "Repository outside synchronization scope")
        require(method == "GET" or (repo == REPO and self.token and not self.dry_run), "Mutation requires repository GITHUB_TOKEN and live mode")
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "w-monitor-collectors-sync", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if data is not None:
            headers["Content-Type"] = "application/json"
        for attempt in range(3 if method == "GET" else 1):
            try:
                request = Request("https://api.github.com/repos/" + repo + path, headers=headers, data=json.dumps(data).encode() if data is not None else None, method=method)
                with self.opener.open(request, timeout=30) as response:
                    raw = response.read(16 * 1024 * 1024 + 1)
                require(len(raw) <= 16 * 1024 * 1024, "GitHub response exceeds bound")
                return json.loads(raw) if raw else None
            except HTTPError as error:
                if repo == SHARED and path.startswith("/actions/") and method == "GET" and error.code == 403 and headers.get("Authorization"):
                    try:
                        message = json.loads(error.read(65536)).get("message")
                    except ValueError:
                        message = None
                    if message == "Resource not accessible by integration" and attempt < 2:
                        print("Shared public Actions GET denied to integration; retrying anonymously", flush=True)
                        headers.pop("Authorization")
                        continue
                if missing and error.code == 404:
                    return None
                if method == "GET" and error.code in (429, 500, 502, 503, 504) and attempt < 2:
                    time.sleep(3)
                    continue
                raise SyncError(method + " " + path + ": HTTP " + str(error.code)) from None
            except (URLError, TimeoutError, OSError) as error:
                if method == "GET" and attempt < 2:
                    time.sleep(3)
                    continue
                raise SyncError(method + " " + path + ": " + type(error).__name__) from None

    def pages(self, repo, path, key=None):
        rows = []
        for page in range(1, 11):
            result = self.call(repo, path + ("&" if "?" in path else "?") + urlencode({"per_page": 100, "page": page}))
            batch = result[key] if key else result
            rows.extend(batch)
            if len(batch) < 100:
                return rows
        raise SyncError("GitHub pagination bound exceeded")

    def files(self, ref):
        result = {}
        for name in FILES:
            value = self.call(REPO, "/contents/" + name + "?" + urlencode({"ref": ref}))
            require(value.get("encoding") == "base64", "Unexpected source encoding")
            result[name] = base64.b64decode(value["content"]).decode()
        return result

    def main(self):
        return self.call(REPO, "/git/ref/heads/main")["object"]["sha"]

    def tag(self, repo, name):
        ref = self.call(repo, "/git/ref/tags/" + quote(name, safe=""), missing=True)
        if ref is None:
            return None
        obj = ref["object"]
        for _ in range(3):
            if obj["type"] == "commit":
                return obj["sha"]
            require(obj["type"] == "tag", "Tag must resolve to a commit")
            obj = self.call(repo, "/git/tags/" + obj["sha"])["object"]
        raise SyncError("Annotated tag nesting exceeds bound")


def shared_package(lock):
    packages = [package for package in tomllib.loads(lock)["package"] if package["name"] == "w-monitor-collectors"]
    require(len(packages) == 1, "Exactly one shared collector lock root is required")
    return packages[0]


def lock_graph(text):
    document = tomllib.loads(text)
    packages = {(package["name"], package["version"], package.get("source", "")): package for package in document["package"]}
    require(len(packages) == len(document["package"]), "Duplicate lock package identity")
    edges = {}
    for identity, package in packages.items():
        dependencies = set()
        for dependency in package.get("dependencies", []):
            parts = dependency.split(" ", 2)
            require(len(parts) < 3 or (parts[2].startswith("(") and parts[2].endswith(")")), "Unsupported lock dependency identity")
            matches = [key for key in packages if key[0] == parts[0] and (len(parts) < 2 or key[1] == parts[1]) and (len(parts) < 3 or key[2] == parts[2][1:-1])]
            require(len(matches) == 1, "Ambiguous or missing lock dependency")
            dependencies.add(matches[0])
        edges[identity] = dependencies
    return document, packages, edges


def reachable(edges, root):
    seen, pending = set(), [root]
    while pending:
        identity = pending.pop()
        if identity not in seen:
            seen.add(identity)
            pending.extend(edges[identity] - seen)
    return seen


def validate_lock(before, after, value):
    old_doc, old_packages, old_edges = lock_graph(before)
    new_doc, new_packages, new_edges = lock_graph(after)
    require({key: item for key, item in old_doc.items() if key != "package"} == {key: item for key, item in new_doc.items() if key != "package"}, "Unrelated lock metadata changed")
    old_shared, new_shared = shared_package(before), shared_package(after)
    require(new_shared["version"] == value["shared_version"] and new_shared["source"] == "git+https://github.com/" + SHARED + "?rev=" + value["shared_sha"] + "#" + value["shared_sha"], "New lock root does not match the exact shared release")
    old_root = (old_shared["name"], old_shared["version"], old_shared["source"])
    new_root = (new_shared["name"], new_shared["version"], new_shared["source"])
    require({key[0] for key in new_edges[new_root]} == ALLOWED_DEPS, "Shared direct lock dependency boundary changed")
    require(not {"w-monitor-sdk", "w-monitor-service"} & {key[0] for key in new_packages}, "Private runtime in regenerated lock graph")
    causal = reachable(old_edges, old_root) | reachable(new_edges, new_root)

    def record(package, edges):
        return {**{key: item for key, item in package.items() if key != "dependencies"}, "dependencies": sorted(edges - causal)}

    def outside(packages, edges):
        return {key: record(package, edges[key]) for key, package in packages.items() if key not in causal and key[0] != "w-monitor-lite"}

    require(outside(old_packages, old_edges) == outside(new_packages, new_edges), "Lock update changed packages outside the shared dependency closures")
    old_apps = [key for key in old_packages if key[0] == "w-monitor-lite"]
    new_apps = [key for key in new_packages if key[0] == "w-monitor-lite"]
    require(len(old_apps) == len(new_apps) == 1, "Exactly one Public application lock root is required")
    old_app, new_app = old_apps[0], new_apps[0]
    require(old_root in old_edges[old_app] and new_root in new_edges[new_app], "Application does not consume the exact shared lock root")
    require({**record(old_packages[old_app], old_edges[old_app]), "version": value["product_version"]} == record(new_packages[new_app], new_edges[new_app]), "Unrelated application lock dependency changed")


def replace_once(text, old, new):
    require(text.count(old) == 1, "Unexpected version/pin declaration")
    return text.replace(old, new)


def release_files(before, old, new):
    declarations = {
        "Cargo.toml": 'version = "{version}"',
        "Cargo.lock": 'name = "w-monitor-lite"\nversion = "{version}"',
        "server/app.py": 'VERSION = "{version}"',
        "server/openapi.json": '"version": "{version}"',
        "README.md": 'The current release is **v{version}**',
        "PROTOCOL.md": '# Public monitoring contract v{version}',
    }
    return {name: replace_once(before[name], declaration.format(version=old), declaration.format(version=new)) for name, declaration in declarations.items()}


def expected_files(before, value, lock):
    old = tomllib.loads(before["Cargo.toml"])["package"]["version"]
    numbers = version(old)
    require(value["product_version"] == ".".join(map(str, (*numbers[:2], numbers[2] + 1))), "Product release must be one patch increment")
    package = shared_package(before["Cargo.lock"])
    require(version(value["shared_version"]) > version(package["version"]), "Shared version must strictly increase")
    old_pin = tomllib.loads(before["Cargo.toml"])["dependencies"]["w-monitor-collectors"]
    require(old_pin.get("git") == "https://github.com/" + SHARED and re.fullmatch(r"[a-f0-9]{40}", old_pin.get("rev", "")), "Current shared dependency must use a fixed public commit")
    require(package["source"] == "git+https://github.com/" + SHARED + "?rev=" + old_pin["rev"] + "#" + old_pin["rev"], "Current shared lock root differs from the pinned manifest")
    result = release_files(before, old, value["product_version"])
    result["Cargo.toml"] = replace_once(result["Cargo.toml"], old_pin["rev"], value["shared_sha"])
    validate_lock(before["Cargo.lock"], lock, value)
    result["Cargo.lock"] = lock
    return result


def run_matches(api, ref, sha):
    return [run for run in api.pages(REPO, "/actions/workflows/ci.yml/runs?" + urlencode({"event": "workflow_dispatch", "head_sha": sha}), "workflow_runs") if run["head_sha"] == sha and run["head_branch"] == ref and run["event"] == "workflow_dispatch"]


def ensure_ci(api, ref, sha, stage, deadline):
    runs = run_matches(api, ref, sha)
    if not runs:
        api.call(REPO, "/actions/workflows/ci.yml/dispatches", "POST", {"ref": ref})
        print("Dispatched CI once:", stage, ref, sha, flush=True)
        # Accepted dispatches become visible asynchronously. Never dispatch again
        # within this invocation; the next schedule queries the same ref/SHA.
        while time.monotonic() < deadline:
            time.sleep(15)
            runs = run_matches(api, ref, sha)
            if runs:
                break
        if not runs:
            print("Waiting for accepted CI dispatch to appear", flush=True)
            return False
    run_id = max(runs, key=lambda run: run["id"])["id"]
    while True:
        run = api.call(REPO, "/actions/runs/" + str(run_id))
        require(run["head_sha"] == sha and run["head_branch"] == ref, "CI reference changed")
        if run["status"] == "completed":
            require(run["conclusion"] == "success", "CI failed; repair or rerun failed jobs manually before reconciliation: " + str(run_id))
            jobs = api.pages(REPO, "/actions/runs/" + str(run_id) + "/jobs?filter=all", "jobs")
            # A manual rerun of only failed regional jobs retains earlier
            # successful jobs. Require each named job's latest attempt to pass.
            latest = {}
            for job in sorted(jobs, key=lambda job: job["id"]):
                latest[job["name"]] = job["conclusion"]
            success = {name for name, conclusion in latest.items() if conclusion == "success"}
            required = {"build-linux-amd64", "build-linux-arm64"} | ({"release"} | DEPLOY_JOBS if stage == "tag" else set())
            require(required <= success, "CI did not complete every required build/release/regional deployment")
            print("Verified CI:", stage, run_id, sha, flush=True)
            return True
        if time.monotonic() >= deadline:
            print("CI pending; next schedule will resume:", stage, run_id, flush=True)
            return False
        time.sleep(20)


def verify_shared(api, value):
    require(api.tag(SHARED, value["shared_tag"]) == value["shared_sha"], "Shared tag moved or does not match pinned commit")
    release = api.call(SHARED, "/releases/tags/" + quote(value["shared_tag"], safe=""))
    require(not release["draft"] and not release["prerelease"], "Shared release is not stable")
    manifest = api.call(SHARED, "/contents/Cargo.toml?" + urlencode({"ref": value["shared_sha"]}))
    require(manifest.get("encoding") == "base64", "Unexpected shared manifest encoding")
    package = tomllib.loads(base64.b64decode(manifest["content"]).decode())["package"]
    require(package["name"] == "w-monitor-collectors" and package["version"] == value["shared_version"], "Shared manifest version differs from its release")
    runs = api.pages(SHARED, "/actions/workflows/ci.yml/runs?" + urlencode({"head_sha": value["shared_sha"]}), "workflow_runs")
    relevant = [run for run in runs if run["head_sha"] == value["shared_sha"] and run["head_branch"] == value["shared_tag"]]
    if not relevant or max(relevant, key=lambda run: run["id"])["status"] != "completed":
        raise Pending("Shared tag CI is pending; the next schedule will check the same release")
    latest = max(relevant, key=lambda run: run["id"])
    require(latest["conclusion"] == "success", "Shared tag CI failed at the exact commit")


def validate_candidate(api, pr):
    commit = api.call(REPO, "/git/commits/" + pr["head"]["sha"])
    value = metadata(commit["message"])
    require(pr["head"]["repo"]["full_name"] == REPO and pr["head"]["ref"] == branch_name(value), "Unexpected PR source branch")
    require(pr["user"]["login"] == BOT and commit["committer"]["email"] == BOT_EMAIL, "Automation will not modify a human branch/PR")
    require([parent["sha"] for parent in commit["parents"]] == [value["base"]], "Candidate has additional or human commits")
    before, after = api.files(value["base"]), api.files(pr["head"]["sha"])
    require(after == expected_files(before, value, after["Cargo.lock"]), "Candidate content differs from the allowed pin/patch-only update")
    comparison = api.call(REPO, "/compare/" + value["base"] + "..." + pr["head"]["sha"])
    require({file["filename"] for file in comparison["files"]} == set(FILES) and all(file["status"] == "modified" for file in comparison["files"]), "Unexpected candidate diff")
    verify_shared(api, value)
    return value


def reconcile(api, pr, deadline):
    value = validate_candidate(api, pr)
    commit_sha = pr["head"]["sha"]
    if not pr["merged_at"]:
        require(pr["state"] == "open", "A human closed the automation PR; manual resolution required")
        require(api.main() == value["base"], "Main advanced; refusing an untested rebase/merge")
        if not ensure_ci(api, pr["head"]["ref"], pr["head"]["sha"], "branch", deadline):
            return False
        # Repository protection must require up-to-date checks to close the
        # remaining GitHub PR-merge API race: sha guards the head, not the base.
        pr = api.call(REPO, "/pulls/" + str(pr["number"]))
        protection = api.call(REPO, "/branches/main").get("protection", {})
        checks = protection.get("required_status_checks", {})
        require(protection.get("enabled") and checks.get("enforcement_level") == "everyone" and {"build-linux-amd64", "build-linux-arm64"} <= set(checks.get("contexts", [])), "Main must enforce both required builds including administrators")
        require(pr["state"] == "open" and not pr["draft"] and pr["mergeable"] is True and pr["mergeable_state"] == "clean", "PR is not clean under required up-to-date branch protection")
        require(pr["base"]["sha"] == value["base"] and api.main() == value["base"], "Main advanced during candidate CI; refusing merge")
        require(pr["head"]["sha"] == commit_sha, "Candidate changed during CI")
        merged = api.call(REPO, "/pulls/" + str(pr["number"]) + "/merge", "PUT", {"sha": pr["head"]["sha"], "merge_method": "merge"})
        require(merged.get("merged") is True, "GitHub refused the guarded merge")
        pr = api.call(REPO, "/pulls/" + str(pr["number"]))
    sha, tag = pr["merge_commit_sha"], "v" + value["product_version"]
    existing = api.tag(REPO, tag)
    if existing is None:
        require(api.main() == sha, "Main advanced before release validation; manual resolution required")
        if not ensure_ci(api, "main", sha, "main", deadline):
            return False
        require(api.main() == sha, "Main advanced during release validation; refusing tag")
        api.call(REPO, "/git/refs", "POST", {"ref": "refs/tags/" + tag, "sha": sha})
    else:
        require(existing == sha, "Immutable product tag already points elsewhere")
    if not ensure_ci(api, tag, sha, "tag", deadline):
        return False
    release = api.call(REPO, "/releases/tags/" + tag)
    require(not release["draft"] and not release["prerelease"], "Product release is not published")
    print("Completed shared update and all seven deployments:", tag, sha, flush=True)
    return True


def create_pr(api, value, branch):
    title = "chore(deps): update shared collectors to " + value["shared_version"]
    body = "Update the exact public shared collector pin and prepare Public v" + value["product_version"] + ".\n\nOnly the reviewed pin, lock and six release declarations may change. CI must pass at each exact commit before merging and releasing. Agent upgrades remain manual.\n\n<!-- " + MARKER + json.dumps(value, sort_keys=True, separators=(",", ":")) + " -->"
    return api.call(REPO, "/pulls", "POST", {"title": title, "head": branch, "base": "main", "body": body})


def prepare(api, base, value):
    before = api.files(base)
    require(all((ROOT / name).read_text() == text for name, text in before.items()), "Checkout is not the expected clean main source")
    old = tomllib.loads(before["Cargo.toml"])["package"]["version"]
    pin = tomllib.loads(before["Cargo.toml"])["dependencies"]["w-monitor-collectors"]["rev"]
    for name, text in release_files(before, old, value["product_version"]).items():
        (ROOT / name).write_text(text)
    path = ROOT / "Cargo.toml"
    path.write_text(replace_once(path.read_text(), pin, value["shared_sha"]))
    subprocess.run(["cargo", "metadata", "--format-version", "1"], cwd=ROOT, timeout=180, check=True, stdout=subprocess.DEVNULL)
    generated = {name: (ROOT / name).read_text() for name in FILES}
    require(generated == expected_files(before, value, generated["Cargo.lock"]), "Regenerated update exceeds allowed scope")
    graph = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT, timeout=120))
    require(not {"w-monitor-sdk", "w-monitor-service"} & {package["name"] for package in graph["packages"]}, "Private runtime in Public graph")
    shared = next(package for package in graph["packages"] if package["name"] == "w-monitor-collectors")
    require(shared["version"] == value["shared_version"] and {dependency["name"] for dependency in shared["dependencies"]} == ALLOWED_DEPS, "Shared dependency boundary changed")
    tree = api.call(REPO, "/git/commits/" + base)["tree"]["sha"]
    tree = api.call(REPO, "/git/trees", "POST", {"base_tree": tree, "tree": [{"path": name, "mode": "100644", "type": "blob", "content": generated[name]} for name in FILES]})["sha"]
    message = "chore(deps): update shared collectors to " + value["shared_version"] + "\n\n<!-- " + MARKER + json.dumps(value, sort_keys=True, separators=(",", ":")) + " -->"
    commit = api.call(REPO, "/git/commits", "POST", {"message": message, "tree": tree, "parents": [base], "author": {"name": BOT, "email": BOT_EMAIL}, "committer": {"name": BOT, "email": BOT_EMAIL}})
    api.call(REPO, "/git/refs", "POST", {"ref": "refs/heads/" + branch_name(value), "sha": commit["sha"]})
    return create_pr(api, value, branch_name(value))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    require(args.dry_run or (os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REPOSITORY") == REPO and os.environ.get("GITHUB_TOKEN")), "Live reconciliation runs only in this repository's Actions with GITHUB_TOKEN")
    api = GitHub(os.environ.get("GITHUB_TOKEN", ""), args.dry_run)
    current = shared_package((ROOT / "Cargo.lock").read_text())["version"]
    latest = api.call(SHARED, "/releases/latest")
    require(not latest["draft"] and not latest["prerelease"], "Latest shared release must be stable")
    target = latest["tag_name"]
    target_version = target.removeprefix("v")
    version(target_version)
    if args.dry_run:
        sha = api.tag(SHARED, target)
        require(sha is not None, "Stable shared release has no tag")
        verify_shared(api, {"shared_tag": target, "shared_version": target_version, "shared_sha": sha})
        print(json.dumps({"current_shared": current, "latest_shared": target_version, "result": "no_update" if version(target_version) <= version(current) else "update_available", "mutations": False}))
        return
    deadline = time.monotonic() + 30 * 60
    base = api.main()
    initial_base = base
    pulls = api.pages(REPO, "/pulls?state=all&sort=created&direction=desc")
    managed = [pr for pr in pulls if pr["head"]["ref"].startswith(PREFIX) and pr["head"]["repo"] and pr["head"]["repo"]["full_name"] == REPO]
    if managed:
        pr = api.call(REPO, "/pulls/" + str(managed[0]["number"]))
        if not reconcile(api, pr, deadline):
            return
        base = api.main()
        if base != initial_base:
            print("Finished prior release; next schedule starts from the updated main")
            return
        current = shared_package(api.files(base)["Cargo.lock"])["version"]
    branches = api.call(REPO, "/git/matching-refs/heads/" + PREFIX)
    orphan = [ref for ref in branches if ref["ref"].removeprefix("refs/heads/") not in {pr["head"]["ref"] for pr in managed}]
    require(len(orphan) <= 1, "Multiple unrecognized update branches require manual inspection")
    if orphan:
        ref = orphan[0]
        value = metadata(api.call(REPO, "/git/commits/" + ref["object"]["sha"])["message"])
        require(value["base"] == base and ref["ref"] == "refs/heads/" + branch_name(value), "Unknown/stale orphan branch; refusing overwrite")
        reconcile(api, create_pr(api, value, branch_name(value)), deadline)
        return
    if version(target_version) <= version(current):
        print("No newer stable shared release; no mutations")
        return
    sha = api.tag(SHARED, target)
    require(sha is not None, "Stable shared release has no tag")
    product = version(tomllib.loads(api.files(base)["Cargo.toml"])["package"]["version"])
    value = {"base": base, "shared_tag": target, "shared_version": target_version, "shared_sha": sha, "product_version": ".".join(map(str, (*product[:2], product[2] + 1)))}
    verify_shared(api, value)
    reconcile(api, prepare(api, base, value), deadline)


if __name__ == "__main__":
    try:
        main()
    except Pending as error:
        print(str(error), flush=True)
    except (SyncError, subprocess.SubprocessError, ValueError, KeyError, StopIteration) as error:
        raise SystemExit("Collector reconciliation stopped: " + str(error)) from None

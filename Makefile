.PHONY: check fmt clippy test repo-check assets acceptance-list vm-doctor image-doctor codex-setup codex-preflight codex-preflight-full

check:
	cargo xtask check

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace --all-features

repo-check:
	cargo xtask repo

assets:
	python3 scripts/validate_assets.py

acceptance-list:
	python3 tools/acceptance.py list

slice-status:
	python3 tools/v010_slice_graph.py status

slice-ready:
	python3 tools/v010_slice_graph.py ready

vm-doctor:
	python3 tools/vm.py doctor

image-doctor:
	python3 tools/image.py doctor

codex-setup:
	bash scripts/setup_codex_environment.sh

codex-preflight:
	bash scripts/preflight_codex_environment.sh

codex-preflight-full:
	bash scripts/preflight_codex_environment.sh --full

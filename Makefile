NAME = $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].name')
VERSION = $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')

DEB_PACKAGE = $(NAME)_$(VERSION)_amd64.deb
TGZ_PACKAGE = $(NAME)_$(VERSION)_linux_amd64.tar.gz
MUSL_TARGET = x86_64-unknown-linux-musl
GNU_TARGET = x86_64-unknown-linux-gnu

all: build
.PHONY: all

build:
	@cargo build --all-targets --target $(MUSL_TARGET)
.PHONY: build

release:
	@cargo build --release --all-targets --target $(MUSL_TARGET)
.PHONY: release

release-gnu:
	@cargo build --release --all-targets --target $(GNU_TARGET)
.PHONY: release-gnu

test:
	@RUST_BACKTRACE=1 cargo test --target $(MUSL_TARGET)
.PHONY: test

check:
	@cargo check --all-targets --target $(MUSL_TARGET)
.PHONY: check

doc:
	@cargo doc --workspace
.PHONY: doc

clean:
	@rm -rf *.log pkg
.PHONY: clean

cleanall: clean
	@cargo clean
.PHONY: cleanall

completion: release
	@mkdir -p target/$(MUSL_TARGET)/release/completion
	@./target/$(MUSL_TARGET)/release/rbw gen-completions bash > target/$(MUSL_TARGET)/release/completion/bash
	@./target/$(MUSL_TARGET)/release/rbw gen-completions zsh > target/$(MUSL_TARGET)/release/completion/zsh
	@./target/$(MUSL_TARGET)/release/rbw gen-completions fish > target/$(MUSL_TARGET)/release/completion/fish
.PHONY: completion

completion-gnu: release-gnu
	@mkdir -p target/$(GNU_TARGET)/release/completion
	@./target/$(GNU_TARGET)/release/rbw gen-completions bash > target/$(GNU_TARGET)/release/completion/bash
	@./target/$(GNU_TARGET)/release/rbw gen-completions zsh > target/$(GNU_TARGET)/release/completion/zsh
	@./target/$(GNU_TARGET)/release/rbw gen-completions fish > target/$(GNU_TARGET)/release/completion/fish
.PHONY: completion-gnu

package: pkg/$(DEB_PACKAGE) pkg/$(TGZ_PACKAGE)
.PHONY: package

pkg:
	@mkdir pkg

pkg/$(DEB_PACKAGE): completion-gnu | pkg
	@cargo deb --no-build --target $(GNU_TARGET) && mv target/$(GNU_TARGET)/debian/$(DEB_PACKAGE) pkg

pkg/$(DEB_PACKAGE).minisig: pkg/$(DEB_PACKAGE)
	@minisign -Sm $<

pkg/$(TGZ_PACKAGE): release completion | pkg
	@tar czf $@ -C target/$(MUSL_TARGET)/release rbw rbw-agent completion

release-dir-deb:
	@ssh partofme mkdir -p releases/rbw/deb
.PHONY: release-dir-deb

publish: publish-crates-io publish-git-tags publish-deb publish-github
.PHONY: publish

publish-crates-io: test
	@cargo publish
.PHONY: publish-crates-io

# force shell instead of exec to work around
# https://savannah.gnu.org/bugs/?57962 since i have ~/.bin/git as a directory
publish-git-tags: test
	@:; git tag $(VERSION)
	@:; git push --tags
.PHONY: publish-git-tags

publish-deb: test pkg/$(DEB_PACKAGE) pkg/$(DEB_PACKAGE).minisig release-dir-deb
	@scp pkg/$(DEB_PACKAGE) pkg/$(DEB_PACKAGE).minisig partofme:releases/rbw/deb
.PHONY: publish-deb

publish-github: test pkg/$(TGZ_PACKAGE)
	@perl -nle'print if /^## \Q[$(VERSION)]/../^## (?!\Q[$(VERSION)]\E)/' CHANGELOG.md | head -n-2 | gh release create $(VERSION) --verify-tag --notes-file - pkg/$(TGZ_PACKAGE)

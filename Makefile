ifeq ($(shell test -f /run/.containerenv && echo y),y)
CRE ?= podman-remote
HOSTCURDIR := $(patsubst /run/host/%,%,$(CURDIR))
else
CRE ?= podman
HOSTCURDIR := $(CURDIR)
endif

GHIDRA_IMAGE ?= mlxini-ghidra-irisc

SYNDICATE_TARBALL_URL ?= https://codeload.github.com/irisc-research-syndicate/ghidra-processor/tar.gz/4c488a43cdbcef957519e3800c3ba796712d3abb
SYNDICATE_TARBALL_SHA256 ?= 666a5551aec5d907a220451e36a5692c1585817b1734d050137a294eb0d565fd
SLASPEC_PATCH_URL ?= https://raw.githubusercontent.com/wipe-coading-survivors/mlxfwinternals/bf9d1535ccd69f8f4b2b211dcc58c726d5ed56de/scripts/irisc/iRISC.slaspec.patch
SLASPEC_PATCH_SHA256 ?= 86b08d2cd0a178b55295d9da74880c467731b18965efe964ede5a163326e3362

-include local.mk

.PHONY: slaspec-prep image

slaspec-prep:
	SYNDICATE_TARBALL_URL='$(SYNDICATE_TARBALL_URL)' \
	SYNDICATE_TARBALL_SHA256='$(SYNDICATE_TARBALL_SHA256)' \
	SLASPEC_PATCH_URL='$(SLASPEC_PATCH_URL)' \
	SLASPEC_PATCH_SHA256='$(SLASPEC_PATCH_SHA256)' \
	$(CURDIR)/scripts/slaspec-prep.sh

image: slaspec-prep
	$(CRE) build -f docker/ghidra-irisc.containerfile -t $(GHIDRA_IMAGE) .

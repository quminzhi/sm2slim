SIZE_MB ?= 16
PASS    ?= pass1234                   # gmssl key password
ID      ?= 1234567812345678

PWD := $(shell pwd)
BUILD_DIR ?= $(PWD)/build
BIN := $(BUILD_DIR)/sm2verify

.PHONY: all sign verify

all: build 

#===========================================
# Verify
#===========================================

MSG_FILE := msg.bin
BAD_FILE := bad.bin
SIG_FILE := msg.sig
PRIV_KEY := sm2.pem
PUB_KEY  := sm2pub.pem
BAD_KEY	:= badpub.pem
KEYSTAMP := .keys.stamp

$(MSG_FILE):
	@echo ">>> Generating $(SIZE_MB) MiB binary file: $@"
	@dd if=/dev/urandom of=$(MSG_FILE) bs=1M count=16

$(BAD_FILE):
	@echo ">>> Generating $(SIZE_MB) MiB binary file: $@"
	@dd if=/dev/urandom of=$(BAD_FILE) bs=1M count=16

$(BAD_KEY):
	@echo ">>> Generating bad SM2 public key"
	@gmssl sm2keygen -pass 'badpass' -out badsm2.pem -pubout $(BAD_KEY)

# Generate SM2 keypair once; both files produced in one shot.
$(KEYSTAMP):
	@echo ">>> Generating SM2 keypair"
	@gmssl sm2keygen -pass '$(PASS)' -out $(PRIV_KEY) -pubout $(PUB_KEY)
	@touch $(KEYSTAMP)

$(PRIV_KEY) $(PUB_KEY): $(KEYSTAMP)

keys: $(PRIV_KEY) $(PUB_KEY)

# Sign the file (DER signature)
$(SIG_FILE): $(MSG_FILE) $(PRIV_KEY) $(PUB_KEY)
	@echo ">>> Signing $(MSG_FILE) -> $(SIG_FILE)"
	@cat $(MSG_FILE) | gmssl sm2sign -key $(PRIV_KEY) -pass '$(PASS)' -id '$(ID)' -out $(SIG_FILE)

sign: $(SIG_FILE)

# Verify the signature with the public key
verify: $(SIG_FILE) $(PUB_KEY) $(MSG_FILE) $(BAD_FILE) $(BAD_KEY)
	@echo ">>> Verifying signature with gmssl library"
	gmssl sm2verify -pubkey $(PUB_KEY) -id '$(ID)' -in '$(MSG_FILE)' -sig $(SIG_FILE)
	@echo ">>> Verifying signature with sm2verify binary"
	$(BIN) -pubkey $(PUB_KEY) -id '$(ID)' -in '$(MSG_FILE)' -sig $(SIG_FILE)
	@echo ">>> Verifying bad signature with gmssl library (should fail)"
	-@gmssl sm2verify -pubkey $(PUB_KEY) -id '$(ID)' -in '$(BAD_FILE)' -sig $(SIG_FILE)
	@echo ">>> Verifying bad signature with sm2verify binary (should fail)"
	-@$(BIN) -pubkey $(PUB_KEY) -id '$(ID)' -in '$(BAD_FILE)' -sig $(SIG_FILE)
	@echo ">>> Verifying signature with bad public key with gmssl library (should fail)"
	-@gmssl sm2verify -pubkey $(BAD_KEY) -id '$(ID)' -in '$(MSG_FILE)' -sig $(SIG_FILE)
	@echo ">>> Verifying signature with bad public key with sm2verify binary (should fail)"
	-@$(BIN) -pubkey $(BAD_KEY) -id '$(ID)' -in '$(MSG_FILE)' -sig $(SIG_FILE)

#===========================================
# Build and Coverage 
#===========================================

.PHONY: build build-with-coverage collect clean clean-verify

build:
	cmake -S . -B build
	cmake --build build

build-with-coverage:
	cmake -S . -B build -DENABLE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug
	cmake --build build

COV_DIR   := $(BUILD_DIR)/coverage
HTML_DIR  := $(BUILD_DIR)/coverage-html
ARCH := $(shell uname -s)

ifeq ($(ARCH),Darwin)
  # 查找 llvm 工具（优先 xcrun，其次 Homebrew）
  BREW_LLVM     := $(shell brew --prefix llvm 2>/dev/null)
  LLVM_COV      ?= $(shell xcrun --find llvm-cov 2>/dev/null || echo $(BREW_LLVM)/bin/llvm-cov)
  LLVM_PROFDATA ?= $(shell xcrun --find llvm-profdata 2>/dev/null || echo $(BREW_LLVM)/bin/llvm-profdata)
  # 生成 .profraw 的文件名模板（避免并发冲突）
  PROFILE_TMPL := $(COV_DIR)/default-%p-%m.profraw
  PROFDATA     := $(COV_DIR)/default.profdata
else
	COVERAGE_INFO := $(BUILD_DIR)/coverage.info
	PROJECT_INFO	:= $(BUILD_DIR)/project.info
endif

ifeq ($(ARCH),Darwin)
collect: build-with-coverage keys sign $(SIG_FILE) $(PUB_KEY) $(MSG_FILE) $(BAD_FILE) $(BAD_KEY)
	@echo ">>> Function should be executed once before run target collect"
	@rm -rf $(COV_DIR) $(HTML_DIR) && mkdir -p $(COV_DIR) $(HTML_DIR)
	@LLVM_PROFILE_FILE=$(PROFILE_TMPL) $(BIN) -pubkey $(PUB_KEY) -id '$(ID)' -in '$(MSG_FILE)' -sig $(SIG_FILE)
	-@LLVM_PROFILE_FILE=$(PROFILE_TMPL) $(BIN) -pubkey $(PUB_KEY) -id '$(ID)' -in '$(BAD_FILE)' -sig $(SIG_FILE)
	-@LLVM_PROFILE_FILE=$(PROFILE_TMPL) $(BIN) -pubkey $(BAD_KEY) -id '$(ID)' -in '$(MSG_FILE)' -sig $(SIG_FILE)
	@$(LLVM_PROFDATA) merge -sparse $(COV_DIR)/*.profraw -o $(PROFDATA)
	@$(LLVM_COV) show $(BIN) -instr-profile=$(PROFDATA) -format=html -output-dir=$(HTML_DIR) -Xdemangler=c++filt
	@echo ">>> Coverage report generated at: file://$(HTML_DIR)/index.html"
else
collect: build-with-coverage keys sign $(SIG_FILE) $(PUB_KEY) $(MSG_FILE) $(BAD_FILE) $(BAD_KEY)
	@echo ">>> Function should be executed once before run target collect"
	@$(BIN) -pubkey $(PUB_KEY) -id '$(ID)' -in '$(MSG_FILE)' -sig $(SIG_FILE)
	-@$(BIN) -pubkey $(PUB_KEY) -id '$(ID)' -in '$(BAD_FILE)' -sig $(SIG_FILE)
	-@$(BIN) -pubkey $(BAD_KEY) -id '$(ID)' -in '$(MSG_FILE)' -sig $(SIG_FILE)
	@lcov --capture --directory $(BUILD_DIR) --base-directory $(PWD) -o $(COVERAGE_INFO)
	@lcov --extract $(COVERAGE_INFO) "$(PWD)/*" -o $(PROJECT_INFO)
	@genhtml $(PROJECT_INFO) --output-directory $(HTML_DIR) --function-coverage
	@echo ">>> Coverage report generated at: file://$(HTML_DIR)/index.html"
endif

clean: clean-verify
	rm -rf build *.profraw

clean-verify:
	rm -rf $(MSG_FILE) $(BAD_FILE) $(SIG_FILE) $(PRIV_KEY) $(PUB_KEY) $(KEYSTAMP) badsm2.pem $(BAD_KEY)


.PHONY: size

size:
	@du -sh include src sm2verify.c ; du -ch include src sm2verify.c | awk '/total$$/'
	

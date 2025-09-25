SIZE_MB ?= 16
PASS    ?= pass1234                   # gmssl key password
ID      ?= 1234567812345678

BIN_FILE := msg.bin
SIG_FILE := msg.sig
PRIV_KEY := sm2.pem
PUB_KEY  := sm2pub.pem
KEYSTAMP := .keys.stamp

SM2VERIFY := ./build/sm2verify

.PHONY: all test sign verify build clean clean-test

all: build 

# Generate bin file, keys, sign, and verify.
test: verify

$(BIN_FILE):
	@echo ">>> Generating $(SIZE_MB) MiB binary file: $@"
	@dd if=/dev/urandom of=$(BIN_FILE) bs=1M count=16

# Generate SM2 keypair once; both files produced in one shot.
$(KEYSTAMP):
	@echo ">>> Generating SM2 keypair"
	@gmssl sm2keygen -pass '$(PASS)' -out $(PRIV_KEY) -pubout $(PUB_KEY)
	@touch $(KEYSTAMP)

$(PRIV_KEY) $(PUB_KEY): $(KEYSTAMP)

keys: $(PRIV_KEY) $(PUB_KEY)

# Sign the file (DER signature)
$(SIG_FILE): $(BIN_FILE) $(PRIV_KEY) $(PUB_KEY)
	@echo ">>> Signing $(BIN_FILE) -> $(SIG_FILE)"
	@cat $(BIN_FILE) | gmssl sm2sign -key $(PRIV_KEY) -pass '$(PASS)' -id '$(ID)' -out $(SIG_FILE)

sign: $(SIG_FILE)

# 4) Verify the signature with the public key
verify: $(SIG_FILE) $(PUB_KEY) $(BIN_FILE)
	@echo ">>> Verifying signature with gmssl library"
	gmssl sm2verify -pubkey $(PUB_KEY) -id '$(ID)' -in '$(BIN_FILE)' -sig $(SIG_FILE)
	@echo ">>> Verifying signature with sm2verify binary"
	$(SM2VERIFY) -pubkey $(PUB_KEY) -id '$(ID)' -in '$(BIN_FILE)' -sig $(SIG_FILE)

build:
	cmake -S . -B build
	cmake --build build

clean: clean-test
	rm -rf build

clean-test:
	rm -rf $(BIN_FILE) $(SIG_FILE) $(PRIV_KEY) $(PUB_KEY) $(KEYSTAMP)


.PHONY: size

size:
	@du -sh include src sm2verify.c ; du -ch include src sm2verify.c | awk '/total$$/'
	

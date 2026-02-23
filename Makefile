# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++11 -pthread
LDFLAGS = -loqs -lcrypto

# Source files
SRC_SERVER = server.cc network.cc crypto.cc
SRC_CLIENT = client.cc network.cc crypto.cc

# Output files
OUT_SERVER = server
OUT_CLIENT = client

# Targets
all: $(OUT_SERVER) $(OUT_CLIENT)

$(OUT_SERVER): $(SRC_SERVER)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(OUT_CLIENT): $(SRC_CLIENT)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Clean up
clean:
	rm -f $(OUT_SERVER) $(OUT_CLIENT)

.PHONY: all clean

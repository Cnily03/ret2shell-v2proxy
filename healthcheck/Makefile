# Optimized Makefile for cross-platform static compilation with clang++

CXX = clang++
CXXFLAGS = -std=c++11 -Wall -Wextra -Oz -flto -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -fmerge-all-constants -fno-math-errno -ffast-math -DNDEBUG -fvisibility=hidden -fvisibility-inlines-hidden

# Build directory
BUILD_DIR = build

# Platform detection
ifeq ($(OS),Windows_NT)
    PLATFORM = WIN32
    LDFLAGS = -static -static-libgcc -static-libstdc++ -lws2_32 -Wl,--gc-sections -Wl,--strip-all -Wl,--strip-debug -Wl,--discard-all -Wl,--build-id=none -flto -s
    TARGET = $(BUILD_DIR)/healthcheck.exe
    MKDIR = if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
    RM = del /Q
    RMDIR = rmdir /S /Q
    STRIP = strip --strip-all $(TARGET)
else
    PLATFORM = UNIX
    LDFLAGS = -static -static-libgcc -static-libstdc++ -Wl,--gc-sections -Wl,--strip-all -Wl,--strip-debug -Wl,--discard-all -Wl,--build-id=none -flto -s
    TARGET = $(BUILD_DIR)/healthcheck
    MKDIR = mkdir -p $(BUILD_DIR)
    RM = rm -f
    RMDIR = rm -rf
    STRIP = strip --strip-all $(TARGET)
endif

# Source files
SOURCES = main.cpp
OBJECTS = $(SOURCES:%.cpp=$(BUILD_DIR)/%.o)

# Default target
all: $(TARGET)

# Create build directory and build target
$(TARGET): $(OBJECTS) | $(BUILD_DIR)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	$(STRIP)
ifeq ($(OS),Windows_NT)
	@for %f in ($(TARGET)) do @echo Build output: %f (%~zf bytes)
else
	@echo "Build output: $(TARGET) ($$(du -h $(TARGET) | cut -f1))"
endif

# Create build directory
$(BUILD_DIR):
	$(MKDIR)

# Compile source files
$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -D$(PLATFORM) -c $< -o $@

# Clean build files
clean:
ifeq ($(OS),Windows_NT)
	if exist $(BUILD_DIR) $(RMDIR) $(BUILD_DIR) 2>nul || true
else
	$(RMDIR) $(BUILD_DIR)
endif

# Install (optional)
install: $(TARGET)
	@echo "Installing $(TARGET)..."
ifeq ($(OS),Windows_NT)
	copy "$(TARGET)" "%SYSTEMROOT%\System32\" >nul
	@echo "Installed to %SYSTEMROOT%\System32\healthcheck.exe"
else
	sudo cp $(TARGET) /usr/local/bin/
	@echo "Installed to /usr/local/bin/healthcheck"
endif

# Ultra-optimized build with UPX compression
ultra: $(TARGET)
ifeq ($(OS),Windows_NT)
	@echo "Compressing with UPX..."
	@upx --best --lzma $(TARGET) 2>nul || echo "UPX not found, skipping compression"
	@for %f in ($(TARGET)) do @echo Ultra-compressed output: %f (%~zf bytes)
else
	@echo "Compressing with UPX..."
	@upx --best --lzma $(TARGET) 2>/dev/null || echo "UPX not found, skipping compression"
	@echo "Ultra-compressed output: $(TARGET) ($$(du -h $(TARGET) | cut -f1))"
endif

.PHONY: all clean install ultra

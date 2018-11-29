LIB_NAME ?= libaes

PROJ_FILES = ../../
LIB_FULL_NAME = $(LIB_NAME).a

VERSION = 1
#############################

-include $(PROJ_FILES)/Makefile.conf
-include $(PROJ_FILES)/Makefile.gen

# use an app-specific build dir
APP_BUILD_DIR = $(BUILD_DIR)/libs/$(LIB_NAME)

# fixme, asm not yet llvm-compatible
#CC := $(CROSS_COMPILE)gcc
CFLAGS := $(DEBUG_CFLAGS) $(WARN_CFLAGS) $(EMBED_CFLAGS) $(AFLAGS)
CFLAGS += -ffreestanding -ffunction-sections -fdata-sections
CFLAGS += -I../common -I../std -I../libecc/src
CFLAGS += -I$(PROJ_FILES)/include/generated -I. -Iarch/cores/$(CONFIG_ARCH) -I$(PROJ_FILES)
CFLAGS += $(APPS_CFLAGS)
CFLAGS += -MMD -MP

LDFLAGS += -fno-builtin -nostdlib -nostartfiles
LD_LIBS += -lsign -L$(BUILD_DIR)

BUILD_DIR ?= $(PROJ_FILE)build

SRC_DIR = .
ALLSRC := $(wildcard $(SRC_DIR)/*.c)
ALLSRC += $(wildcard $(SRC_DIR)/**/*.c)

# if AES test benchmark is not activated,
# AES tests are not compiled-in
ifndef CONFIG_USR_LIB_AES_PERF
SRC = $(filter-out ./tests/aes_tests.c,$(ALLSRC))
else
SRC = $(ALLSRC)
endif

ASM = $(wildcard $(SRC_DIR)/aes_anssi/**/*.S)

OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
ASM_OBJ = $(patsubst %.S,$(APP_BUILD_DIR)/%.o,$(ASM))
DEP = $(OBJ:.o=.d)

OUT_DIRS = $(dir $(OBJ)) $(dir $(ARCH_OBJ))

# file to (dist)clean
# objects and compilation related
TODEL_CLEAN += $(ARCH_OBJ) $(OBJ)
# targets
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

.PHONY: app

default: all

all: $(APP_BUILD_DIR) lib

show:
	@echo
	@echo "\tAPP_BUILD_DIR\t=> " $(APP_BUILD_DIR)
	@echo
	@echo "C sources files:"
	@echo "\tSRC_DIR\t\t=> " $(SRC_DIR)
	@echo "\tSRC\t\t=> " $(SRC)
	@echo "\tASM\t\t=> " $(ASM)
	@echo "\tOBJ\t\t=> " $(OBJ)
	@echo "\tASM_OBJ\t\t=> " $(ASM_OBJ)
	@echo

lib: $(APP_BUILD_DIR)/$(LIB_FULL_NAME)

#############################################################
# build targets (driver, core, SoC, Board... and local)
# App C sources files
$(APP_BUILD_DIR)/%.o: %.c
	$(call if_changed,cc_o_c)

$(APP_BUILD_DIR)/%.o: %.S
	$(call if_changed,cc_o_c)

# lib
$(APP_BUILD_DIR)/$(LIB_FULL_NAME): $(OBJ) $(ASM_OBJ)
	$(call if_changed,mklib)
	$(call if_changed,ranlib)

$(APP_BUILD_DIR):
	$(call cmd,mkdir)

-include $(DEP)
-include $(DRVDEP)
-include $(TESTSDEP)

LIB_NAME ?= libaes

PROJ_FILES = ../../
LIB_FULL_NAME = $(LIB_NAME).a

# this library is a concatenation of a local basic implementation
# and a secured, masked implementation using an external project
LOCAL_LIB_NAME = libgenaes.a

VERSION = 1
#############################

-include $(PROJ_FILES)/Makefile.conf
-include $(PROJ_FILES)/Makefile.gen

# use an app-specific build dir
APP_BUILD_DIR = $(BUILD_DIR)/libs/$(LIB_NAME)

CFLAGS += $(LIBS_CFLAGS)
# fixme, asm not yet llvm-compatible
CFLAGS += -ffreestanding -ffunction-sections -fdata-sections
CFLAGS += -I../common -I../std -I../libecc/src
CFLAGS += -I$(PROJ_FILES)/include/generated -Iapi -I. -Iarch/cores/$(CONFIG_ARCH) -I$(PROJ_FILES)
CFLAGS += $(APPS_CFLAGS)
CFLAGS += -MMD -MP -Os

LDFLAGS += -fno-builtin -nostdlib -nostartfiles
LD_LIBS += -lsign -L$(BUILD_DIR)

BUILD_DIR ?= $(PROJ_FILE)build

EXTERNALLIB = $(BUILD_DIR)/externals/libmaskedaes.a

SRC_DIR = .
ALLSRC := $(wildcard $(SRC_DIR)/*.c)
ALLSRC += $(wildcard $(SRC_DIR)/**/*.c)
ALLSRC += $(wildcard $(SRC_DIR)/**/**/*.c)

# if AES test benchmark is not activated,
# AES tests are not compiled-in
ifndef CONFIG_USR_LIB_AES_PERF
SRC = $(filter-out ./tests/aes_tests.c,$(ALLSRC))
else
SRC = $(ALLSRC)
endif


OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
DEP = $(OBJ:.o=.d)

OUT_DIRS = $(dir $(OBJ)) $(dir $(ARCH_OBJ))

# file to (dist)clean
# objects and compilation related
TODEL_CLEAN += $(ARCH_OBJ) $(OBJ)
# targets
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

.PHONY: app doc

default: all

all: $(APP_BUILD_DIR) lib

doc:

show:
	@echo
	@echo "\tAPP_BUILD_DIR\t=> " $(APP_BUILD_DIR)
	@echo
	@echo "C sources files:"
	@echo "\tSRC_DIR\t\t=> " $(SRC_DIR)
	@echo "\tSRC\t\t=> " $(SRC)
	@echo "\tOBJ\t\t=> " $(OBJ)
	@echo

lib: $(APP_BUILD_DIR)/$(LIB_FULL_NAME)

#############################################################
# build targets (driver, core, SoC, Board... and local)
# App C sources files
$(APP_BUILD_DIR)/%.o: %.c
	$(call if_changed,cc_o_c)

# lib
$(APP_BUILD_DIR)/$(LIB_FULL_NAME): $(APP_BUILD_DIR)/$(LOCAL_LIB_NAME) $(EXTERNALLIB)
	$(call if_changed,fusionlib)

$(APP_BUILD_DIR)/$(LOCAL_LIB_NAME): $(OBJ)
	$(call if_changed,mklib)
	$(call if_changed,ranlib)


$(APP_BUILD_DIR):
	$(call cmd,mkdir)

-include $(DEP)
-include $(DRVDEP)
-include $(TESTSDEP)

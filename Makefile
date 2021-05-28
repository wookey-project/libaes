###################################################################
# About the library name and path
###################################################################

# library name, without extension
LIB_NAME ?= libaes

# project root directory, relative to app dir
PROJ_FILES = ../../

# library name, with extension
LIB_FULL_NAME = $(LIB_NAME).a

# libaes specific:
# this library is a concatenation of a local basic implementation
# and a secured, masked implementation using an external project
LOCAL_LIB_NAME = libgenaes.a

# SDK helper Makefiles inclusion
-include $(PROJ_FILES)/m_config.mk
-include $(PROJ_FILES)/m_generic.mk

# use an app-specific build dir
APP_BUILD_DIR = $(BUILD_DIR)/libs/$(LIB_NAME)

###################################################################
# About the compilation flags
###################################################################

CFLAGS += $(LIBS_CFLAGS)
# fixme, asm not yet llvm-compatible
CFLAGS += -I../libecc/src
CFLAGS += -Iapi
CFLAGS += -MMD -MP
# Optimizing for size has a huge performance impact (performances
# are almost half the ones measured with -O3 flag)
CFLAGS += -Os

BUILD_DIR ?= $(PROJ_FILE)build

# libaes specific: part of it is an external component
EXTERNALLIB = $(BUILD_DIR)/externals/libmaskedaes.a

#############################################################
# About library sources
#############################################################

SRC_DIR = .
ALLSRC := $(wildcard $(SRC_DIR)/*.c)
ALLSRC += $(wildcard $(SRC_DIR)/**/*.c)
ALLSRC += $(wildcard $(SRC_DIR)/**/**/*.c)

# if AES test benchmark is not activated,
# AES tests are not compiled-in


# FIXME: RBE: is it possible, instead of filter-out, to add preprocessing inside to
# empty the file ? This would avoid to create differenciate *source lists* for 
# FW and DFU mode.
# Otherwise, it is required to define SRC_FW and SRC_DFU instead of SRC, which
# is less readable :-/
ifndef CONFIG_USR_LIB_AES_PERF
SRC = $(filter-out ./tests/aes_tests.c,$(ALLSRC))
else
SRC = $(ALLSRC)
endif

# two build types: separated FW and DFU featureset, or single global featureset.
# This build type is controlled by USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD flag.
# In case of separated build, all objects, deps and libary files are written
# in dfu/ and fw/ subdirectories, and the current makefile build two independent
# libraries, with a differenciate additional cflag to detect DFU build: -DMODE_DFU
ifeq (y,$(CONFIG_USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD))
OBJ_FW = $(patsubst %.c,$(APP_BUILD_DIR)/fw/%.o,$(SRC))
OBJ_DFU = $(patsubst %.c,$(APP_BUILD_DIR)/dfu/%.o,$(SRC))
DEP_FW = $(OBJ_FW:.o=.d)
DEP_DFU = $(OBJ_DFU:.o=.d)
else
OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
DEP = $(OBJ:.o=.d)
endif

OUT_DIRS = $(dir $(OBJ))

# file to (dist)clean
# objects and compilation related
ifeq (y,$(CONFIG_USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD))
TODEL_CLEAN += $(OBJ_FW) $(OBJ_DFU)
else
TODEL_CLEAN += $(OBJ)
endif
# targets
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

##########################################################
# generic targets of all libraries makefiles
##########################################################

.PHONY: app doc

default: all

ifeq (y,$(CONFIG_USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD))
all: $(APP_BUILD_DIR)  $(APP_BUILD_DIR)/dfu $(APP_BUILD_DIR)/fw lib
else
all: $(APP_BUILD_DIR) lib
endif

doc:

show:
	@echo
	@echo "\tAPP_BUILD_DIR\t=> " $(APP_BUILD_DIR)
	@echo
	@echo "C sources files:"
	@echo "\tSRC_DIR\t\t=> " $(SRC_DIR)
	@echo "\tSRC\t\t=> " $(SRC)
ifeq (y,$(CONFIG_USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD))
	@echo "\tOBJ_FW\t\t=> " $(OBJ_FW)
	@echo "\tOBJ_DFU\t\t=> " $(OBJ_DFU)
	@echo
	$(Q)$(MAKE) show_dfu_cflags
	$(Q)$(MAKE) show_fw_cflags
else
	@echo "\tOBJ\t\t=> " $(OBJ)
endif
	@echo


ifeq (y,$(CONFIG_USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD))
# assigning a dedicated cflags to show_dfu_flags only
show_dfu_cflags: CFLAGS += -DMODE_DFU
show_dfu_cflags:
	@echo "\tDFU_CFLAGS\t=> " $(CFLAGS)

show_fw_cflags:
	@echo "\tFW_CFLAGS\t=> " $(CFLAGS)
endif



ifeq (y,$(CONFIG_USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD))
lib: $(APP_BUILD_DIR)/dfu/$(LIB_FULL_NAME) $(APP_BUILD_DIR)/fw/$(LIB_FULL_NAME)
else
lib: $(APP_BUILD_DIR)/$(LIB_FULL_NAME)
endif

#############################################################
# build targets (driver, core, SoC, Board... and local)
# App C sources files
#



# in case of differenciate build, here is the metholodogy:
#
# two obj file lists: one in fw/ subdir, one in dfu/ subdirs.
# In order to inform the C code which (fw or dfu) lib is currently being
# compiled, an additional CFLAGS is passed to DFU library only, by
# appending -DMODE_DFU to DFU OBJS build command cc_o_cc through
# the locally upgraded only CFLAGS variable.
ifeq (y,$(CONFIG_USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD))

# here: build fw mode library object files
$(APP_BUILD_DIR)/fw/%.o: %.c
	$(call if_changed,cc_o_c)


# here: build dfu mode library object files
# assigning a dedicated cflags to DFU objs file build only
# see GNU Make(1) target specific variales
$(APP_BUILD_DIR)/dfu/%.o: CFLAGS += -DMODE_DFU
$(APP_BUILD_DIR)/dfu/%.o: %.c
	$(call if_changed,cc_o_c)
#
else
# in case of common library (without dfu/fw dedicated featureset), nothing
# special is done.
$(APP_BUILD_DIR)/%.o: %.c
	$(call if_changed,cc_o_c)
endif

# lib

# in case of dedicated fw/dfu mode featureset, two libraries are fusion with the
# external libSecAES lib. There is no differenciated libSecAES usage here.
#
ifeq (y,$(CONFIG_USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD))
$(APP_BUILD_DIR)/dfu/$(LIB_FULL_NAME): $(APP_BUILD_DIR)/dfu/$(LOCAL_LIB_NAME) $(EXTERNALLIB)
	$(call if_changed,fusionlib)

$(APP_BUILD_DIR)/fw/$(LIB_FULL_NAME): $(APP_BUILD_DIR)/fw/$(LOCAL_LIB_NAME) $(EXTERNALLIB)
	$(call if_changed,fusionlib)

else
$(APP_BUILD_DIR)/$(LIB_FULL_NAME): $(APP_BUILD_DIR)/$(LOCAL_LIB_NAME) $(EXTERNALLIB)
	$(call if_changed,fusionlib)
endif


# in case of dedicated fw/dfu mode featureset, two libraries are built based on
# the localy built library. There is no dfu or fw specific action here, just two
# libraries that are built
#
ifeq (y,$(CONFIG_USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD))
$(APP_BUILD_DIR)/dfu/$(LOCAL_LIB_NAME): $(OBJ_DFU)
	$(call if_changed,mklib)
	$(call if_changed,ranlib)

$(APP_BUILD_DIR)/fw/$(LOCAL_LIB_NAME): $(OBJ_FW)
	$(call if_changed,mklib)
	$(call if_changed,ranlib)
else
$(APP_BUILD_DIR)/$(LOCAL_LIB_NAME): $(OBJ)
	$(call if_changed,mklib)
	$(call if_changed,ranlib)
endif


$(APP_BUILD_DIR):
	$(call cmd,mkdir)

ifeq (y,$(CONFIG_USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD))
$(APP_BUILD_DIR)/dfu:
	$(call cmd,mkdir)


$(APP_BUILD_DIR)/fw:
	$(call cmd,mkdir)
endif

ifeq (y,$(CONFIG_USR_LIB_AES_DIFFERENCIATE_DFU_FW_BUILD))
-include $(DEP_FW)
-include $(DEP_DFU)
else
-include $(DEP)
endif
-include $(DRVDEP)
-include $(TESTSDEP)

#Set this variable to point to your SDK directory
IDA_SDK=../../

SDKVER=$(shell pwd | grep -o -E "idasdk[_a-z]*[0-9]{2,3}" | grep -o -E "[0-9]+")
IDAVER=$(shell pwd | grep -o -E "idasdk[_a-z]*[0-9]{2,3}" | grep -o -E "[0-9]+" | sed 's/\(.\)\(.\)/\1\.\2/')
IDAVER_MAJOR=$(shell pwd | grep -o -E "idasdk[_a-z]*[0-9]{2,3}" | grep -o -E "[0-9]+" | cut -c 1)

$(info $$SDKVER is [${SDKVER}])
$(info $$IDAVER is [${IDAVER}])
$(info $$IDAVER_MAJOR is [${IDAVER_MAJOR}])

PLATFORM=$(shell uname | cut -f 1 -d _)

#Set this variable to the desired name of your compiled plugin
PROC=blc

ifeq "$(PLATFORM)" "Linux"
#Make a best guess about where user's ida was installed
IDA=$(shell if [ -f /opt/ida-$(IDAVER)/libida.so ]; then echo -n /opt/ida-$(IDAVER); else echo -n /opt/idapro-$(IDAVER); fi)
HAVE_IDA64=$(shell if [ -f $(IDA)/libida64.so ]; then echo -n yes; fi)
PLATFORM_CFLAGS=-D__LINUX__ -D__UNIX__
PLATFORM_LDFLAGS=-shared -s
IDADIR=-L$(IDA)

ifeq "$(IDAVER_MAJOR)" "6"
PLUGIN_EXT32=.plx
PLUGIN_EXT64=.plx64
else
PLUGIN_EXT32=.so
PLUGIN_EXT64=64.so
endif

IDALIB32=-lida
IDALIB64=-lida64

else ifeq "$(PLATFORM)" "Darwin"

IDAHOME=/Applications/IDA Pro $(IDAVER)

ifeq "$(IDAVER_MAJOR)" "6"
IDA=$(shell dirname "`find "$(IDAHOME)" -name idaq | tail -n 1`")
PLUGIN_EXT32=.pmc
PLUGIN_EXT64=.pmc64
else
IDA=$(shell dirname "`find "$(IDAHOME)" -name ida | tail -n 1`")
PLUGIN_EXT32=.dylib
PLUGIN_EXT64=64.dylib
endif

HAVE_IDA64=$(shell find "$(IDA)" -name libida64.dylib -exec echo -n yes \;)
PLATFORM_CFLAGS=-D__MAC__ -D__UNIX__
PLATFORM_LDFLAGS=-dynamiclib
IDADIR=-L"$(IDA)"

IDALIB32=-lida
IDALIB64=-lida64
endif

ifeq "$(IDAVER_MAJOR)" "6"
CFLAGS=-Wextra -Os $(PLATFORM_CFLAGS) -m32 -fPIC
LDFLAGS=$(PLATFORM_LDFLAGS) -m32
else
CFLAGS=-Wextra -Os $(PLATFORM_CFLAGS) -D__X64__ -m64  -fPIC
LDFLAGS=$(PLATFORM_LDFLAGS) -m64
endif

CFLAGS+= -std=c++11

# Destination directory for compiled plugins
OUTDIR=./bin/

OBJDIR32=obj32
OBJDIR64=obj64

SRCS=action.cc address.cc architecture.cc ast.cc \
    block.cc blockaction.cc callgraph.cc capability.cc \
    cast.cc comment.cc condexe.cc context.cc coreaction.cc \
    cover.cc cpool.cc crc32.cc database.cc double.cc dynamic.cc \
    emulate.cc emulateutil.cc filemanage.cc float.cc flow.cc \
    fspec.cc funcdata.cc funcdata_block.cc funcdata_op.cc \
    funcdata_varnode.cc globalcontext.cc grammar.tab.cc graph.cc \
    heritage.cc ida_arch.cc ida_load_image.cc ida_scope.cc \
    ifacedecomp.cc inject_sleigh.cc interface.cc jumptable.cc \
    libdecomp.cc loadimage.cc memstate.cc merge.cc op.cc \
    opbehavior.cc opcodes.cc options.cc override.cc paramid.cc \
    pcodecompile.cc pcodeinject.cc pcodeparse.tab.cc pcoderaw.cc \
    plugin.cc prefersplit.cc prettyprint.cc printc.cc printjava.cc \
    printlanguage.cc rangeutil.cc ruleaction.cc run.cc semantics.cc \
    sleigh.cc sleigh_arch.cc sleighbase.cc slghpatexpress.cc \
    slghpattern.cc slghsymbol.cc space.cc stringmanage.cc \
    subflow.cc testfunction.cc transform.cc translate.cc type.cc \
    typeop.cc unionresolve.cc userop.cc variable.cc varmap.cc \
    varnode.cc xml.tab.cc xml_tree.cc

OBJS32 := $(patsubst %.cc, $(OBJDIR32)/%.o, $(SRCS) )
OBJS64 := $(patsubst %.cc, $(OBJDIR64)/%.o, $(SRCS) )

BINARY32=$(OUTDIR)$(PROC)$(PLUGIN_EXT32)
BINARY64=$(OUTDIR)$(PROC)$(PLUGIN_EXT64)

ifdef HAVE_IDA64

all: $(OUTDIR) $(BINARY32) $(BINARY64)

clean:
	-@rm $(OBJS32)
	-@rm $(OBJS64)
	-@rm $(BINARY32)
	-@rm $(BINARY64)

else

all: $(OUTDIR) $(BINARY32)

clean:
	-@rm $(OBJS32)
	-@rm $(BINARY32)

endif

install: all
	-@echo 'Copying blc plugin(s) to "$(IDA)/plugins"'
	-@cp $(OUTDIR)/* "$(IDA)/plugins"
	-@echo 'Extracting Ghidra sleigh files to "$(IDA)/plugins"'
	-@tar -xf blc_sleigh_files.tgz -C "$(IDA)/plugins"

$(OUTDIR):
	-@mkdir -p $(OUTDIR)

$(OBJDIR32):
	-@mkdir -p $(OBJDIR32)

$(OBJDIR64):
	-@mkdir -p $(OBJDIR64)

CC=g++
INC=-I$(IDA_SDK)include/ -I./include/

LD=g++

$(OBJDIR32)/%.o: %.cc
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

$(OBJDIR64)/%.o: %.cc
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

$(BINARY32): $(OBJDIR32) $(OBJS32) $(SRCS)
	$(LD) $(LDFLAGS) -o $@ $(CFLAGS) $(SRCS) $(INC) $(IDADIR) $(IDALIB32) $(EXTRALIBS) 

ifdef HAVE_IDA64

$(BINARY64): $(OBJDIR64) $(OBJS64) $(SRCS)
	$(LD) $(LDFLAGS) -o $@ -D__EA64__ $(CFLAGS) $(SRCS) $(INC) $(IDADIR) $(IDALIB64) $(EXTRALIBS) 

endif

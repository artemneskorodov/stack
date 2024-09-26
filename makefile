FLAGS:=-I include -Wshadow -Winit-self -Wredundant-decls -Wcast-align -Wundef -Wfloat-equal -Winline -Wunreachable-code -Wmissing-declarations -Wmissing-include-dirs -Wswitch-enum -Wswitch-default -Weffc++ -Wmain -Wextra -Wall -g -pipe -fexceptions -Wcast-qual -Wconversion -Wctor-dtor-privacy -Wempty-body -Wformat-security -Wformat=2 -Wignored-qualifiers -Wlogical-op -Wno-missing-field-initializers -Wnon-virtual-dtor -Woverloaded-virtual -Wpointer-arith -Wsign-promo -Wstack-usage=8192 -Wstrict-aliasing -Wstrict-null-sentinel -Wtype-limits -Wwrite-strings -Werror=vla -D_DEBUG -D_EJUDGE_CLIENT_SIDE
SRCDIR:=src
BINDIR:=bin
EXENAME:=stack.exe
OBJECTS:=$(notdir $(patsubst %.cpp,%.o,$(wildcard $(SRCDIR)/*)))

all: ${EXENAME}

${EXENAME}:	$(addprefix ${BINDIR}\,${OBJECTS})
	g++ main.cpp $(addprefix ${BINDIR}\,${OBJECTS}) ${FLAGS} -o ${EXENAME}
$(addprefix ${BINDIR}\,${OBJECTS}): ${BINDIR} $(patsubst %.o,%.cpp,$(addprefix ${SRCDIR}\,$(notdir ${OBJECTS})))
	g++ -c $(patsubst %.o,%.cpp,$(addprefix ${SRCDIR}\,$(notdir $@))) ${FLAGS} -o $@
clean:
	del ${EXENAME}
	$(foreach OBJ,${OBJECTS},$(shell del $(addprefix ${BINDIR}\,${OBJ})))
${BINDIR}:
ifeq ("$(wildcard ${BINDIR})", "")
	mkdir ${BINDIR}
endif

$(patsubst %.o,%.cpp,$(addprefix ${SRCDIR}\,$(notdir ${OBJECTS}))):


CXX:=g++
STD:=-std=c++14
CFLAGS:=-Wall -Werror -Wextra -Weffc++ -pedantic
DEBUG_FLAGS:=-g

SRC:=$(wildcard *.cpp)
INC:=$(wildcard include/*.h)
OBJ:=$(SRC:%.cpp=obj/%.o)
DEP:=$(SRC:%.cpp=dep/%.d)
TRGT:=main.exe

INCLUDES:=-isysteminclude -I../include

$(TRGT): setup $(OBJ)
	$(CXX) -lgmpxx -lgmp $(OBJ) -o $@

setup:
	@mkdir -p obj
	@mkdir -p dep

-include $(DEP)

obj/%.o: %.cpp $(INC)
	$(CXX) $(STD) $(DEBUG_FLAGS) $(CFLAGS) $(INCLUDES) -MF dep/$(<:.cpp=.d) -MMD -c $< -o $@

clean:
	rm -rf obj dep $(TRGT) test_output  $(HTML) *.dat

test: $(TEST) $(TRGT)
	contest contest.yaml

.PHONY:all clean test setup

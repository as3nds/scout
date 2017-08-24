

# because with colors the life is more beautiful!

COLOR_RED 		= 1
COLOR_GREEN		= 2
COLOR_YELLOW 	= 3
COLOR_BLUE 		= 4
COLOR_MAGENTA 	= 5
COLOR_CYAN		= 6
COLOR_WHITE		= 7

define echo_color
	@tput setaf $1 
	@echo $2
	@tput sgr0
endef
define echo_colorn
	@tput setaf $1 
	@echo -n $2
	@tput sgr0
endef

# OK_STRING 		= $(OK_COLOR)[OK]$(NO_COLOR)
# ERROR_STRING 	= $(ERROR_COLOR)[ERRORS]$(NO_COLOR)
# WARN_STRING 	= $(WARN_COLOR)[WARNINGS]$(NO_COLOR)
NB_WARNING =  cat test.log | grep warning | wc | grep -o '[0-9]\+' | head -n 1
NB_ERROR = cat test.log | grep error | wc | grep -o '[0-9]\+' | head -n 1

CC 		= gcc
CFLAGS 	= -std=c99 -Wall -I.

LINKER 	= gcc
LFLAGS 	= -Wall -I. -lm

scout: engine.o ipv4.o
	$(call echo_color, $(COLOR_WHITE), "Linking "$@"...")
	$(LINKER) -o $@ $? $(LFLAGS)
	$(call echo_color, $(COLOR_GREEN), "[OK]")

ipv4.o: ipv4.c
	$(call echo_color, $(COLOR_WHITE), "Compiling "$<"...")
	$(CC) $(CFLAGS) -c $< -o $@
	$(call echo_color, $(COLOR_GREEN), "[OK]")

engine.o: engine.c
	$(call echo_color, $(COLOR_WHITE), "Compiling "$<"...")
	$(CC) $(CFLAGS) -c $< -o $@ 2>test.log
	$(call echo_color, $(COLOR_GREEN), "[OK]")




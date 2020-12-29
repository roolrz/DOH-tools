CC := gcc

ALL_SRCF := $(shell find . -type f -name "*.c")
ALL_OBJF := $(patsubst %.c,%.o,$(ALL_SRCF))

CFLAGS := -Wall -Werror -Wno-unused-function -MMD
COLORF := -DCOLOR
DFLAGS := -g -DDEBUG -DCOLOR
PRINT_STAMENTS := -DERROR -DSUCCESS -DWARN -DINFO

STD := -std=gnu11

CFLAGS += $(STD)

EXEC := dohdig

.PHONY: clean all setup debug

all: setup $(EXEC)

debug: CFLAGS += $(DFLAGS) $(PRINT_STAMENTS) $(COLORF)
debug: all

setup: $(BLDD)
$(EXEC): $(ALL_OBJF)
	$(CC) $^ -o $@ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(ALL_OBJF) $(EXEC) *.d

.PRECIOUS: $(BLDD)/*.d
-include $(BLDD)/*.d

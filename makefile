# הגדרת המהדר
CC = gcc

# דגלים: 
# -g לדיבאג
# -m32 חובה כדי לקמפל לסביבת 32-סיביות
# -Wall להצגת כל האזהרות
CFLAGS = -g -m32 -Wall -D_FILE_OFFSET_BITS=64

# קבצי יעד
all: myELF

myELF: myELF.o
	$(CC) $(CFLAGS) -o myELF myELF.o

myELF.o: myELF.c
	$(CC) $(CFLAGS) -c myELF.c

# ניקוי קבצים זמניים
.PHONY: clean
clean:
	rm -f *.o myELF
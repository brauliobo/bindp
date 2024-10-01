TARGET=libindp.so

all:
	gcc -nostartfiles -fpic -shared bindp.c -o ${TARGET} -ldl

clean:
	rm ${TARGET} -f

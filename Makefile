LDFLAGS = `sh osflags ld`
CFLAGS = -c -g `sh osflags c`
TUN_DEV_FILE = `sh osflags dev`

all: hans

hans: tun.o sha1.o main.o client.o server.o auth.o worker.o time.o tun_dev.o echo.o exception.o utility.o
	g++ -o hans tun.o sha1.o main.o client.o server.o auth.o worker.o time.o tun_dev.o echo.o exception.o utility.o $(LDFLAGS)

utility.o: utility.cpp utility.h
	g++ -c utility.cpp $(CFLAGS)

exception.o: exception.cpp exception.h
	g++ -c exception.cpp $(CFLAGS)

echo.o: echo.cpp echo.h exception.h
	g++ -c echo.cpp $(CFLAGS)

tun.o: tun.cpp tun.h exception.h utility.h tun_dev.h
	g++ -c tun.cpp $(CFLAGS)

tun_dev.o:
	gcc -c $(TUN_DEV_FILE) -o tun_dev.o $(CFLAGS)

sha1.o: sha1.cpp sha1.h
	g++ -c sha1.cpp $(CFLAGS)

main.o: main.cpp client.h server.h exception.h worker.h auth.h time.h echo.h tun.h tun_dev.h
	g++ -c main.cpp $(CFLAGS)

client.o: client.cpp client.h server.h exception.h config.h worker.h auth.h time.h echo.h tun.h tun_dev.h
	g++ -c client.cpp $(CFLAGS)

server.o: server.cpp server.h client.h utility.h config.h worker.h auth.h time.h echo.h tun.h tun_dev.h
	g++ -c server.cpp $(CFLAGS)

auth.o: auth.cpp auth.h sha1.h utility.h
	g++ -c auth.cpp $(CFLAGS)

worker.o: worker.cpp worker.h tun.h exception.h time.h echo.h tun_dev.h config.h
	g++ -c worker.cpp $(CFLAGS)

time.o: time.cpp time.h
	g++ -c time.cpp $(CFLAGS)

clean:
	rm -f tun.o sha1.o main.o client.o server.o auth.o worker.o time.o tun_dev.o echo.o exception.o utility.o hans


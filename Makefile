CC=gcc
FLAGS=-Iinclude -pthread # -Wall
TARGET=sniffer

sniffer: src/sniffer.c src/daemon.c include/sniffer.h
	$(CC) $(FLAGS) -o $(TARGET) src/sniffer.c src/daemon.c
run: sniffer
	sudo ./$(TARGET)
kill:
	#sudo kill -9 $(ps -C controller -o pid=)
	ps -C $(TARGET) -o pid= | xargs sudo kill -9 
terminate:
	ps -C $(TARGET) -o pid= | xargs sudo kill -TERM
clean:
	rm -rf *.o $(TARGET)

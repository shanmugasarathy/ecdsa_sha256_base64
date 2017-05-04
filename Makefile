CC = gcc
CFLAGS = -I/usr/include -g
LDFLAGS = -lcrypto -lssl
SRC = Curl_Post_Sign.c

TARGET = curl_post_sign

all: $(TARGET)

$(TARGET): clean
	$(CC) $(SRC) -o $(TARGET) $(CFLAGS) $(LDFLAGS)

clean:
	$(RM) $(TARGET)

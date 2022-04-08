all: clean setup

setup:
	go build main.go

clean:
	rm -rf 'main' main.go
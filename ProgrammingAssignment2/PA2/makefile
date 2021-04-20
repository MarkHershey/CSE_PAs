REMOVE = rm -vf
CC = javac


# Explicit rules, all the commands you can call with make 
# (note: the <tab> in the command line is necessary for make to work) 
# target:  dependency1 dependency2 ...
#       <tab> command

#Called by: make targetname 
#also executed when you just called make. This calls the first target. 
all: target_main

target_main:
	$(CC) *.java

clean:
	$(REMOVE) *.class
	$(REMOVE) server_storage/recv_*
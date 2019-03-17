all:
	make otp_enc_d otp_dec_d otp_enc otp_dec

otp_enc_d: otp_enc_d.o
	gcc -o otp_enc_d otp_enc_d.o

otp_enc_d.o: otp_enc_d.c
	gcc -c -g -Wall otp_enc_d.c

otp_dec_d: otp_dec_d.o
	gcc -o otp_dec_d otp_dec_d.o

otp_dec_d.o: otp_dec_d.c
	gcc -c -g -Wall otp_dec_d.c

otp_enc: otp_enc.o
	gcc -o otp_enc otp_enc.o

otp_enc.o: otp_enc.c
	gcc -c -g -Wall otp_enc.c 

otp_dec: otp_dec.o
	gcc -o otp_dec otp_dec.o

otp_dec.o: otp_dec.c
	gcc -c -g -Wall otp_dec.c 

clean:
	rm *.o client server

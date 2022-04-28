#!/usr/bin/python3
import faker
f = faker.Faker()
x = input('Enter number for passwords:')
for i in range(x):
	#print(f.password())
	fle.write(f.password()+"\n")
	fle.flush()
fle.close()
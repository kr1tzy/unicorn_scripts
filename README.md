# Unicorn Scripts

> Simple scripts to teach Unicorn and how to build an AFL-Unicorn test harness. Dockerfile included with all the necessary setup.

## Working with Docker

Run the following commands to get up and running

```sh
docker-compose build
docker-compose up -d
docker exec -it unicorn_scripts /bin/bash
```

Then ```cd scripts``` and have fun

![examples](img/examples.png)

## Scripts

### Example 1

_No stack or data region_

Adds and subtracts values from rax and outputs the result.

### Example 2

_Has a stack but no data region_

Pushes & pops values and adds two registers then outputs the results.

### Example 3

_Has a stack and data region_

Mimics a function prologue and makes room for a local variable; sets the address of the data region as a local variable; dereferences that address and puts the value in rax; outputs the results.  

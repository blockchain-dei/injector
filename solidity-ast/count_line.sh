#!/bin/bash
search_dir=/Users/fernandovidal/srv04/
for entry in "$search_dir"/*
do
     echo "$entry"
     
     qtd= wc -l  < "$entry" 
     
done
    
package com.sample.ldap.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {

    @GetMapping
    public ResponseEntity<String> getMethod() {
        return new ResponseEntity<String>("SUCCESS", HttpStatus.OK);
    }

}

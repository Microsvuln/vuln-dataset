package com.vontobel.devops.gitops.springbootdastexample.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class IndexController {

    @GetMapping("/")
    public List<String> listEndpoints() {
        List<String> endpoints = Arrays.asList(
                "/users",
                "/users/search?username=admin",
                "/greet?name=John",
                "/upload", // Add the new vulnerable file upload endpoint
                "/upload-form",
                "/edit-user-form?id=1",
                "/update-user",
                "/view-profile?id=1",
                "/login-form",
                "/create-user-form",
                "/create-user-form-secure",
                "/save-query-mh",
                "/read-query",
                "/save-query",
                "/save-complex-query",
                "/execute-command?command=",
                "/execute-command2?command=",
                "/user-agent" // Add the new form endpoint
                // Add other endpoints here
        );

        return endpoints;
    }
}

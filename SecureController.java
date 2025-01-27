package com.vontobel.devops.gitops.springbootdastexample.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/secure")
public class SecureController {
  @GetMapping("/ping")
  private String ping() {
    return "pong";
  }
}

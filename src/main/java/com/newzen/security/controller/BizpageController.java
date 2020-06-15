package com.newzen.security.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class BizpageController {

    @GetMapping("/index")
    public String index() {
        return "index";
    }

    @GetMapping("/syslog")
    public String showOrder() {
        return "syslog";
    }

    @GetMapping("/sysuser")
    public String addOrder() {
        return "sysuser";
    }

    @GetMapping("/biz1")
    public String updateOrder() {
        return "biz1";
    }

    @GetMapping("/biz2")
    public String deleteOrder() {
        return "biz2";
    }


}

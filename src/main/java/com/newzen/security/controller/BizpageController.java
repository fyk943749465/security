package com.newzen.security.controller;


import com.newzen.security.model.PersonDemo;
import com.newzen.security.service.MethodELService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

@Controller
public class BizpageController {

    @Resource
    private MethodELService methodELService;


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
//        methodELService.findAll();
//        methodELService.findOne();

//      List<Integer> ids = new ArrayList<>();
//      ids.add(1);
//      ids.add(2);
//      methodELService.delete(ids,null);

      List<PersonDemo> pds = methodELService.findAllPD();
        return "biz1";
    }

    @GetMapping("/biz2")
    public String deleteOrder() {
        return "biz2";
    }


}

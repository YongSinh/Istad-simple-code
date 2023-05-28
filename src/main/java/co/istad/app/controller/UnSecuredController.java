package co.istad.app.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("anonymous")
public class UnSecuredController {

    @GetMapping("/test")
    String test() {
        return "For anonymous";
    }
}

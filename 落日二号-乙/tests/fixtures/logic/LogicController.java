package com.example.logic;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class LogicController {

    private final UserRepository repo = new UserRepository();
    private final AccountService account = new AccountService();

    @GetMapping("/users/{id}")
    public Object getUser(@PathVariable Long id) {
        return repo.findById(id);
    }

    @PostMapping("/transfer")
    public void transfer(@RequestParam BigDecimal amount, @RequestParam Long to) {
        account.setAmount(amount);
        account.transfer(to);
    }

    static class UserRepository {
        Object findById(Long id) { return null; }
    }

    static class AccountService {
        void setAmount(BigDecimal amount) { }
        void transfer(Long to) { }
    }
}

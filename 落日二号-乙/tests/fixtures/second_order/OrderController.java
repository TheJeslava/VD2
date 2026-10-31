package com.example.orders;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/orders")
public class OrderController {

    @Autowired
    private JdbcTemplate jdbc;

    @PostMapping("/create")
    public void create(@RequestParam String name) {
        jdbc.update("INSERT INTO orders(name) VALUES ('" + name + "')");
    }

    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam String q) {
        String stored = jdbc.queryForObject("SELECT name FROM orders WHERE id = 1", String.class);
        return jdbc.queryForList("SELECT * FROM orders WHERE name = '" + stored + "'");
    }
}

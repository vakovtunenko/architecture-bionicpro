package com.bionicpro.reports.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReportsController {
    @GetMapping("/reports")
    @PreAuthorize("hasRole('prothetic_user')")
    public String getReports() {
        return "These are reports";
    }
}

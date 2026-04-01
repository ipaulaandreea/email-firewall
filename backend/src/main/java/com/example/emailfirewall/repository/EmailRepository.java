package com.example.emailfirewall.repository;

import com.example.emailfirewall.entity.EmailEntity;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface EmailRepository extends JpaRepository<EmailEntity, UUID> {

    @EntityGraph(attributePaths = {"authResults"})
    List<EmailEntity> findTop50ByOrderByReceivedAtDesc();
}

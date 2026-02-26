package com.example.emailfirewall.repository;

import com.example.emailfirewall.entity.RuleHitEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RuleHitRepository extends JpaRepository<RuleHitEntity, Long> {
    List<RuleHitEntity> findByEmail_IdOrderByHitAtAsc(java.util.UUID emailId);
}

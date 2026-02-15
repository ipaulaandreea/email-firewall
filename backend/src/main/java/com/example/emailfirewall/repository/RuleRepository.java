package com.example.emailfirewall.repository;

import com.example.emailfirewall.entity.RuleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface RuleRepository extends JpaRepository<RuleEntity, UUID> {
    List<RuleEntity> findByEnabledTrueOrderByPriorityAsc();
}

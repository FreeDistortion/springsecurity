package com.example.springsecurity.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Table(name = "sample")
@Entity
@SequenceGenerator(
        name = "seq_gen",
        initialValue = 1,
        allocationSize = 1,
        sequenceName = "sample_SEQ"
)
public class SampleEntity {
    @Id
    @GeneratedValue(generator = "seq_gen")
    private Long id;
    private String username;
    private String password;
    private String name;

    public SampleEntity(String username, String password, String name) {
        this.username = username;
        this.password = password;
        this.name = name;
    }
}

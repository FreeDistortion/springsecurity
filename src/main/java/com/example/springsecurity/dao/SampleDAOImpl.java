package com.example.springsecurity.dao;

import com.example.springsecurity.model.SampleEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class SampleDAOImpl {

    private final SampleRepository sampleRepository;
//    @Override
    public void write(SampleEntity entity){
        sampleRepository.save(entity);
    }
//    @Override
    public SampleEntity login(String username){
        return sampleRepository.findByUsername(username);
    }
}

package com.khomsi.site_project;


import com.khomsi.site_project.entity.Product;
import com.khomsi.site_project.repository.ProductRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

//@Rollback(value = false)
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class ProductRepositoryTest {
    @Autowired
    ProductRepository productRepository;

    @Test
    void testFindByAlias() {
        String alias = "samsung";

        Product product = productRepository.findByAlias(alias);

        assertThat(product).isNotNull();
    }
}

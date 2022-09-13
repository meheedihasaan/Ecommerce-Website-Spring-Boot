package com.khomsi.site_project.service;

import com.khomsi.site_project.entity.Category;
import com.khomsi.site_project.exception.CategoryNotFoundException;
import org.springframework.data.domain.Page;

import java.util.List;

public interface ICategoryService {
    public List<Category> listCategoriesUserInForm();
    public Category saveCategory(Category category);

    public void deleteCategory(int id) throws CategoryNotFoundException;

    public Category getCategory(Integer id) throws CategoryNotFoundException;
    public Category getCategoryByAlias(String alias) throws CategoryNotFoundException;

    //list up parent of categories
    List<Category> getCategoryParents(Category child);

    Page<Category> listByPage(int pageNum);

    String checkCategoryTitle(Integer id, String title);
}

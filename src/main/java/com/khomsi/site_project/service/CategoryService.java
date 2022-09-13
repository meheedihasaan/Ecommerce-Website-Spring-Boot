package com.khomsi.site_project.service;

import com.khomsi.site_project.entity.Category;
import com.khomsi.site_project.exception.CategoryNotFoundException;
import com.khomsi.site_project.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

@Service
public class CategoryService implements ICategoryService {
    @Autowired
    private CategoryRepository categoryRep;

    public static final int CATEGORIES_PER_PAGE = 5;

    @Override
    public List<Category> listCategoriesUserInForm() {
        List<Category> categoriesUserInForm = new ArrayList<>();

        Iterable<Category> categoriesInDB = categoryRep.findAll();

        for (Category category : categoriesInDB) {
            if (category.getParent() == null) {
                categoriesUserInForm.add(Category.copyIdAndTitle(category));

                Set<Category> children = category.getChildren();

                for (Category subCat : children) {
                    String name = "--" + subCat.getTitle();
                    categoriesUserInForm.add(Category.copyIdAndTitle(subCat.getId(), name));

                    listChildren(categoriesUserInForm, subCat, 1);
                }
            }
        }
        return categoriesUserInForm;
    }

    private void listChildren(List<Category> categoriesUserInForm, Category parent, int subLevel) {
        int newSubLevel = subLevel + 1;

        Set<Category> children = parent.getChildren();

        for (Category subCategory : children) {
            String name = "";
            for (int i = 0; i < newSubLevel; i++) {
                name += "--";
            }
            name += subCategory.getTitle();
            categoriesUserInForm.add(Category.copyIdAndTitle(subCategory.getId(), name));
            listChildren(categoriesUserInForm, subCategory, newSubLevel);
        }
    }

    @Override
    public Category saveCategory(Category category) {
        Category parent = category.getParent();
        if (parent != null) {
            String allParentIds = parent.getAllParentsIDs() == null ? "-" : parent.getAllParentsIDs();
            allParentIds += String.valueOf(parent.getId()) + "-";
            category.setAllParentsIDs(allParentIds);
        }
        if (category.getAlias() == null || category.getAlias().isEmpty()) {
            String defaultAlias = category.getTitle().toLowerCase();
            category.setAlias(convertCyrillic(defaultAlias).replaceAll(" ", "_"));
        } else {
            category.setAlias(category.getAlias().replaceAll(" ", "_").toLowerCase());
        }
        return categoryRep.save(category);
    }

    //Method to convert alias into english letters
    public String convertCyrillic(String message) {
        char[] abcCyr = {' ', 'а', 'б', 'в', 'г', 'д', 'і', 'е', 'ж', 'з', 'ѕ', 'и', 'ј', 'к', 'л', 'ґ', 'м', 'н', 'є',
                'о', 'п', 'р', 'с', 'т', 'ї', 'у', 'ф', 'х', 'ц', 'ч', 'џ', 'ш', 'А', 'Б', 'В', 'Г', 'Д', 'І', 'Е', 'Ж',
                'З', 'Ѕ', 'И', 'Ј', 'К', 'Л', 'Ґ', 'М', 'Н', 'Є', 'О', 'П', 'Р', 'С', 'Т', 'Ї', 'У', 'Ф', 'Х', 'Ц', 'Ч',
                'Џ', 'Ш', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '/'};

        String[] abcLat = {" ", "a", "b", "v", "g", "d", "i", "e", "zh", "z", "y", "i", "j", "k", "l", "g", "m", "n", "e",
                "o", "p", "r", "s", "t", "ї", "u", "f", "h", "c", "ch", "x", "h", "A", "B", "V", "G", "D", "І", "E", "Zh",
                "Z", "Y", "I", "J", "K", "L", "G", "M", "N", "E", "O", "P", "R", "S", "T", "I", "U", "F", "H", "C", ":",
                "X", "{", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s",
                "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N",
                "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "_"};
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < message.length(); i++) {
            for (int x = 0; x < abcCyr.length; x++) {
                if (message.charAt(i) == abcCyr[x]) {
                    builder.append(abcLat[x]);
                }
            }
        }
        return builder.toString();
    }

    @Override
    public void deleteCategory(int id) throws CategoryNotFoundException {
        Long countById = categoryRep.countById(id);
        if (countById == null || countById == 0) {
            throw new CategoryNotFoundException("Couldn't find any category with id " + id);
        }
        categoryRep.deleteById(id);
    }

    @Override
    public Category getCategory(Integer id) throws CategoryNotFoundException {
        try {
            return categoryRep.getReferenceById(id);
        } catch (NoSuchElementException e) {
            throw new CategoryNotFoundException("Couldn't find any category with id " + id);
        }
    }

    @Override
    public Category getCategoryByAlias(String alias) throws CategoryNotFoundException {
        Category category = categoryRep.findByAliasEnabled(alias);
        if (category == null) {
            throw new CategoryNotFoundException("Couldn't find any category with alias " + alias);
        }
        return category;
    }

    //list up parent of categories
    @Override
    public List<Category> getCategoryParents(Category child) {
        List<Category> listParents = new ArrayList<>();
        Category parent = child.getParent();

        //look up to parent by loop
        while (parent != null) {
            listParents.add(0, parent);
            parent = parent.getParent();
        }
        listParents.add(child);

        return listParents;
    }

    @Override
    public Page<Category> listByPage(int pageNum) {
        Pageable pageable = PageRequest.of(pageNum - 1, CATEGORIES_PER_PAGE);
        return categoryRep.findAll(pageable);
    }

    @Override
    public String checkCategoryTitle(Integer id, String title) {
        Category category = categoryRep.findByTitle(title);
        boolean isCreatingNew = (id == null);

        if (isCreatingNew) {
            if (category != null) return "Duplicate";
        } else {
            if (category.getId() != id) {
                return "Duplicate";
            }
        }
        return "OK";
    }

}

package com.example.samuraitravel.controller;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.samuraitravel.entity.House;
import com.example.samuraitravel.form.HouseRegisterForm;
import com.example.samuraitravel.repository.HouseRepository;

@Controller
// ルートパスの基準値を設定している、このクラス内でのパスはhouses/〇〇となる
@RequestMapping("/admin/houses")
public class AdminHouseController {
	// 定数の場合はfinalを宣言
	private final HouseRepository houseRepository;
	
	// コンストラクタ、本来は@Autowiredが必要→コンストラクタが一つの場合は省略可能
	public AdminHouseController(HouseRepository houseRepository) {
		this.houseRepository = houseRepository;
	}
	
	// 宿泊施設一覧表示
	@GetMapping
    public String index(
    		@PageableDefault(page = 0, size = 10, sort = "id", direction = Direction.ASC) Pageable pageable, 
    		@RequestParam(name = "keyword", required = false) String keyword,
    		Model model) {
//		// findAllで全リストを取得
//		List<House> houses = houseRepository.findAll();
		// page型のオブジェクトの生成
//		Page<House> housePage = houseRepository.findAll(pageable);
		Page<House> housePage;
		
		//kwywordの入力があればkeywordに該当するものを絞り込んで検索、取得
		if(keyword != null && !keyword.isEmpty()) {
			housePage = houseRepository.findByNameLike("%" + keyword + "%", pageable);
		} else {
			housePage = houseRepository.findAll(pageable);
		}
//		
//		model.addAttribute("houses",houses);
		model.addAttribute("housePage",housePage);
		model.addAttribute("keyword",keyword);
		
		return "admin/houses/index";
		
	}
	
	// 宿泊施設の詳細表示
	@GetMapping("/{id}") 
	public String detail(
			@PathVariable(name = "id") Integer id,
			Model model) {
		House house = houseRepository.getReferenceById(id);
		
		model.addAttribute("house" , house);
		return "admin/houses/show";
	}
	
	@GetMapping("/register")
	public String register(Model model) {
		model.addAttribute("houseRegisterForm", new HouseRegisterForm());
		return "admin/houses/register";
	}
}

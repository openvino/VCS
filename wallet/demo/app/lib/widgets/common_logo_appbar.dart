
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class CustomLogoAppBar extends AppBar {
  CustomLogoAppBar({super.key})
      : super(
          systemOverlayStyle: SystemUiOverlayStyle.light, // 2
          automaticallyImplyLeading: false,
          title: const Text('Manatoko ID', style: TextStyle( fontWeight: FontWeight.w700)),
          toolbarHeight: 50,
          flexibleSpace: Container(
            height: 200,
            color: const Color(0xfffcca40),
          ),
        );
}

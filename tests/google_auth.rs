use std::fs;

use authfix::multifactor::factor_impl::authenticator::TotpSecretGenerator;
use authfix_test_utils::{test_out_path, TEST_OUT};
use image::GrayImage;
use resvg::{tiny_skia, usvg};

#[test]
fn should_contain_valid_url() {
    let gen = TotpSecretGenerator::new("TestApp", "john.doe@example.org");
    let secret = gen.secret();
    let qr_code = gen.qr_code().unwrap();

    let options = usvg::Options::default();
    let tree = usvg::Tree::from_str(&qr_code, &options).unwrap();

    let size = tree.size();
    let width = size.width() as u32;
    let height = size.height() as u32;

    let mut pixmap = tiny_skia::Pixmap::new(width, height).unwrap();
    resvg::render(&tree, tiny_skia::Transform::default(), &mut pixmap.as_mut());
    fs::create_dir_all(TEST_OUT).unwrap();
    pixmap.save_png(test_out_path("qr_code.png")).unwrap();

    let img: GrayImage = image::open(test_out_path("qr_code.png"))
        .unwrap()
        .to_luma8();
    let mut img = rqrr::PreparedImage::prepare(img);
    let grids = img.detect_grids();
    let (_, content) = grids[0].decode().unwrap();

    assert_eq!(
        content,
        format!(
            "otpauth://totp/TestApp:john.doe@example.org?secret={}&issuer=TestApp&digits=6",
            secret
        )
    );
}

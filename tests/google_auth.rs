use std::fs;

use auth_middleware_for_actix_web::multifactor::google_auth::TotpSecretGenerator;
use image::GrayImage;
use resvg::{tiny_skia, usvg};
use test_utils::{test_out_path, TEST_OUT};

mod test_utils;

#[test]
fn should_contain_valid_url() {
    let gen = TotpSecretGenerator::new();
    let secret = gen.create_secret();
    let qr_code =
        TotpSecretGenerator::create_qr_code(&secret, "TestApp", "john.doe@example.org").unwrap();

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

$(document).ready(function() {
    $('#Login').click(function() {
        var email = document.getElementById('email').value;
        var password = document.getElementById('password').value;
        var basicInfo = JSON.stringify({
            email: email,
            password: password
        });

        $.ajax({
            type: "POST",
            url: "/auth/login",
            dataType: 'json',
            contentType: "application/json; charset=utf-8",
            data: basicInfo,
            success: function(data) {
                localStorage.token = data.token;
                window.location.href = "/user/profile";
            },
            error: function() {
                alert("Đăng nhập thất bại. Vui lòng kiểm tra lại thông tin!");
            }
        });
    });

    if (window.location.pathname === '/user/profile') {
        $.ajax({
            type: 'GET',
            url: '/users/me',
            dataType: 'json',
            contentType: "application/json; charset=utf-8",
            beforeSend: function(xhr) {
                if (localStorage.token) {
                    xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.token);
                }
            },
            success: function(data) {
                $('#profile').text("Xin chào, " + data.fullName);
                $('#email-info').text("Email của bạn: " + data.email);
            },
            error: function() {
                alert("Phiên đăng nhập không hợp lệ hoặc đã hết hạn.");
                window.location.href = "/login";
            }
        });
    }

    $('#Logout').click(function() {
        localStorage.clear();
        window.location.href = "/login";
    });
});
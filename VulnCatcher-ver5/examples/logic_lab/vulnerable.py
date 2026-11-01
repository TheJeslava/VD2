"""故意存在缺陷的最小复现；HTTP 服务实际调用这些被分析的函数。"""


def reset_password(body, session, store):
    # 对应 014 的流程缺陷：最终操作没有检查验证码状态。
    store.change_password(session['user_id'], body['password'])
    return {'status': 200}


def reset_password_client_flag(body, session, store):
    # 对应 015 的信任缺陷：用户自己提交“已通过”。
    if not body.get('passed_captcha'):
        return {'status': 403}
    store.change_password(session['user_id'], body['password'])
    return {'status': 200}


def update_order(body, session, store):
    order = store.get_order(body['order_id'])
    store.update_order(order['id'], body['memo'])
    return {'status': 200}


def purchase(body, session, store):
    quantity = body['quantity']
    store.purchase(session['user_id'], quantity)
    return {'status': 200}

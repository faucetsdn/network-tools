def routes():
    import paths
    p = endpoints()
    create_r = paths.CreateR()
    delete_r = paths.DeleteR()
    info_r = paths.InfoR()
    list_r = paths.ListR()
    start_r = paths.StartR()
    stop_r = paths.StopR()
    funcs = [create_r,
             delete_r,
             info_r,
             list_r,
             start_r,
             stop_r]
    return dict(list(zip(p, funcs)))


def endpoints():
    return ['/create',
            '/delete',
            '/info',
            '/list',
            '/start',
            '/stop']

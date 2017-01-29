void read_postdata(struct mybufs **, struct mg_connection *conn);
void copy_postdata_to_mg(struct mg_connection *, struct mybufs *);
extern int sflag;
extern int vflag;
extern int Dflag;
extern pthread_key_t local_store;
